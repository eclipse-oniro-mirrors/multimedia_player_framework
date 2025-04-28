/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avtranscoder.h"
#include "media_core.h"
#include "media_log.h"
#include "cj_avtranscoder_callback.h"

namespace OHOS {
namespace Media {

std::unordered_map<CjAVTransCoderOpt, const char *, EnumClassHash> OPT2CSTR = {
    {CjAVTransCoderOpt::PREPARE, "Prepare"},
    {CjAVTransCoderOpt::START, "Start"},
    {CjAVTransCoderOpt::PAUSE, "Pause"},
    {CjAVTransCoderOpt::RESUME, "Resume"},
    {CjAVTransCoderOpt::CANCEL, "Cancel"},
    {CjAVTransCoderOpt::RELEASE, "Release"},
    {CjAVTransCoderOpt::SET_FD, "SetFd"}
};

std::unordered_map<CjAVTransCoderState, const char *, EnumClassHash> STATE2CSTR = {
    {CjAVTransCoderState::STATE_IDLE, "idle"},
    {CjAVTransCoderState::STATE_PREPARED, "prepared"},
    {CjAVTransCoderState::STATE_STARTED, "started"},
    {CjAVTransCoderState::STATE_PAUSED, "paused"},
    {CjAVTransCoderState::STATE_CANCELLED, "cancelled"},
    {CjAVTransCoderState::STATE_COMPLETED, "completed"},
    {CjAVTransCoderState::STATE_RELEASED, "released"},
    {CjAVTransCoderState::STATE_ERROR, "error"}

};

const std::unordered_map<CjAVTransCoderState, std::vector<CjAVTransCoderOpt>, EnumClassHash> STATE_LIST = {
    {CjAVTransCoderState::STATE_IDLE, {
        CjAVTransCoderOpt::SET_FD,
        CjAVTransCoderOpt::PREPARE,
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_PREPARED, {
        CjAVTransCoderOpt::START,
        CjAVTransCoderOpt::CANCEL,
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_STARTED, {
        CjAVTransCoderOpt::PAUSE,
        CjAVTransCoderOpt::CANCEL,
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_PAUSED, {
        CjAVTransCoderOpt::RESUME,
        CjAVTransCoderOpt::CANCEL,
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_CANCELLED, {
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_COMPLETED, {
        CjAVTransCoderOpt::RELEASE
    }},
    {CjAVTransCoderState::STATE_RELEASED, {}},
    {CjAVTransCoderState::STATE_ERROR, {
        CjAVTransCoderOpt::RELEASE
    }},
};

int64_t CJAVTranscoder::CreateAVTranscoder(int32_t* errorcode)
{
    CJAVTranscoder *cjAVTranscoder = FFIData::Create<CJAVTranscoder>();
    if (cjAVTranscoder == nullptr) {
        MEDIA_LOGE("No memory!");
        *errorcode = MSERR_EXT_API9_NO_MEMORY;
        return INVALID_ID;
    }

    cjAVTranscoder->transCoder_ = TransCoderFactory::CreateTransCoder();
    if (cjAVTranscoder->transCoder_ == nullptr) {
        FFIData::Release(cjAVTranscoder->GetID());
        MEDIA_LOGE("failed to CreateTransCoder");
        *errorcode = MSERR_EXT_API9_NO_MEMORY;
        return INVALID_ID;
    }

    cjAVTranscoder->transCoderCb_ = std::make_shared<CJAVTranscoderCallback>();
    (void)cjAVTranscoder->transCoder_->SetTransCoderCallback(cjAVTranscoder->transCoderCb_);

    MEDIA_LOGI("Constructor success");
    *errorcode = MSERR_EXT_API9_OK;
    return cjAVTranscoder->GetID();
}

int32_t CJAVTranscoder::GetReturnRet(int32_t errCode)
{
    MediaServiceExtErrCodeAPI9 err = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errCode));
    MEDIA_LOGE("errCode: %{public}d, err: %{public}d", errCode, err);
    return err;
}

int32_t CJAVTranscoder::GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, AudioCodecFormat> mimeStrToCodecFormat = {
        { MediaAVCodec::CodecMimeType::AUDIO_AAC, AudioCodecFormat::AAC_LC },
        { "", AudioCodecFormat::AUDIO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CJAVTranscoder::GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat)
{
    MEDIA_LOGI("mime %{public}s", mime.c_str());
    const std::map<std::string_view, VideoCodecFormat> mimeStrToCodecFormat = {
        { MediaAVCodec::CodecMimeType::VIDEO_AVC, VideoCodecFormat::H264 },
        { MediaAVCodec::CodecMimeType::VIDEO_HEVC, VideoCodecFormat::H265 },
        { "", VideoCodecFormat::VIDEO_DEFAULT },
    };

    auto iter = mimeStrToCodecFormat.find(mime);
    if (iter != mimeStrToCodecFormat.end()) {
        codecFormat = iter->second;
        return MSERR_OK;
    }
    return MSERR_INVALID_VAL;
}

int32_t CJAVTranscoder::GetOutputFormat(const std::string &extension, OutputFormatType &type)
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

int32_t CJAVTranscoder::GetConfig(const CAVTransCoderConfig &cconfig, CjAVTransCoderConfig &config)
{
    int32_t ret = GetAudioCodecFormat(std::string(cconfig.audioCodecFormat), config.audioCodecFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "GetAudioCodecFormat failed");

    ret = GetVideoCodecFormat(std::string(cconfig.videoCodecFormat), config.videoCodecFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "GetVideoCodecFormat failed");

    ret = GetOutputFormat(std::string(cconfig.fileFormat), config.fileFormat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "GetOutputFormat failed");

    config.audioBitrate = cconfig.audioBitrate;
    config.videoBitrate = cconfig.videoBitrate;
    config.videoFrameWidth = cconfig.videoFrameWidth;
    config.videoFrameHeight = cconfig.videoFrameHeight;

    return MSERR_OK;
}

void CJAVTranscoder::StateCallback(CjAVTransCoderState state)
{
    if (STATE2CSTR.find(state) != STATE2CSTR.end()){
        MEDIA_LOGI("Change state to %{public}s", STATE2CSTR.at(state));
    } else {
        MEDIA_LOGW("state %{public}d is not in STATE2CSTR", static_cast<int32_t>(state));
    }

    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    CjAVTransCoderState curState = cjCb->GetState();
    if (curState == CjAVTransCoderState::STATE_ERROR && state != CjAVTransCoderState::STATE_RELEASED) {
        MEDIA_LOGI("current state is error, only can execute release");
        return;
    }
    cjCb->SendStateCallback(state, StateChangeReason::USER);
}

int32_t CJAVTranscoder::CheckStateMachine(CjAVTransCoderOpt opt)
{
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    CHECK_AND_RETURN_RET_LOG(cjCb != nullptr, MSERR_NO_MEMORY, "cjCb is nullptr!");

    CjAVTransCoderState curState = cjCb->GetState();
    CHECK_AND_RETURN_RET_LOG(STATE_LIST.find(curState) != STATE_LIST.end(),
        MSERR_INVALID_VAL, "state is not in list");
    std::vector<CjAVTransCoderOpt> allowedOpt = STATE_LIST.at(curState);
    if (find(allowedOpt.begin(), allowedOpt.end(), opt) == allowedOpt.end()) {
        if ((OPT2CSTR.find(opt) == OPT2CSTR.end()) || (STATE2CSTR.find(curState) == STATE2CSTR.end())) {
            MEDIA_LOGW("opt %{public}d is not in OPT2CSTR or state %{public}d is not in STATE2CSTR",
                static_cast<int32_t>(opt), static_cast<int32_t>(curState));
            MEDIA_LOGE("The %{public}d operation is not allowed in the %{public}d state!",
                static_cast<int32_t>(opt), static_cast<int32_t>(curState));
        } else {
            MEDIA_LOGE("The %{public}s operation is not allowed in the %{public}s state!",
                OPT2CSTR.at(opt), STATE2CSTR.at(curState));
        }
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

void CJAVTranscoder::CancelCallback()
{
    CHECK_AND_RETURN_LOG(transCoderCb_ != nullptr, "transCoderCb_ is nullptr!");
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->ClearCallbackReference();
}

int32_t CJAVTranscoder::Prepare(std::shared_ptr<TransCoder> transCoder, const CAVTransCoderConfig &cconfig)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::PREPARE);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    CjAVTransCoderConfig config;
    ret = GetConfig(cconfig, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_EXT_API9_INVALID_PARAMETER, "GetConfig failed");

    if (hasConfiged_) {
        MEDIA_LOGE("CjAVTransCoderConfig has been configured and will not be configured again");
        return MSERR_EXT_API9_OK;
    }

    ret = transCoder->SetOutputFormat(config.fileFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    ret = transCoder->SetAudioEncoder(config.audioCodecFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    ret = transCoder->SetAudioEncodingBitRate(config.audioBitrate);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    ret = transCoder->SetVideoEncoder(config.videoCodecFormat);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    ret = transCoder->SetVideoSize(config.videoFrameWidth, config.videoFrameHeight);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    ret = transCoder->SetVideoEncodingBitRate(config.videoBitrate);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    hasConfiged_ = true;

    ret = transCoder->Prepare();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ((void)transCoder->Cancel(), GetReturnRet(ret)));

    StateCallback(CjAVTransCoderState::STATE_PREPARED);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::Start(std::shared_ptr<TransCoder> transCoder)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::START);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    ret = transCoder->Start();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    StateCallback(CjAVTransCoderState::STATE_STARTED);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::Pause(std::shared_ptr<TransCoder> transCoder)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::PAUSE);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    ret = transCoder->Pause();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    StateCallback(CjAVTransCoderState::STATE_PAUSED);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::Resume(std::shared_ptr<TransCoder> transCoder)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::RESUME);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    ret = transCoder->Resume();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    StateCallback(CjAVTransCoderState::STATE_STARTED);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::Cancel(std::shared_ptr<TransCoder> transCoder)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::CANCEL);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    ret = transCoder->Cancel();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    StateCallback(CjAVTransCoderState::STATE_CANCELLED);
    hasConfiged_ = false;
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::Release(std::shared_ptr<TransCoder> transCoder)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::RELEASE);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    
    ret = transCoder->Release();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    StateCallback(CjAVTransCoderState::STATE_RELEASED);
    CancelCallback();
    hasConfiged_ = false;
    return MSERR_EXT_API9_OK;
}

CAVFileDescriptor CJAVTranscoder::GetInputFile()
{
    return CAVFileDescriptor{
        .fd = fdSrc_.fd, .offset = fdSrc_.offset, .length = fdSrc_.length};
}

int32_t CJAVTranscoder::SetInputFile(std::shared_ptr<TransCoder> transCoder, CAVFileDescriptor fdSrc)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::SET_FD);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));

    fdSrc_.fd = fdSrc.fd;
    fdSrc_.offset = fdSrc.offset;
    fdSrc_.length = fdSrc.length;
    ret = transCoder->SetInputFile(fdSrc_.fd, fdSrc_.offset, fdSrc_.length);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::GetOutputFile()
{
    return fdDst_;
}

int32_t CJAVTranscoder::SetOutputFile(std::shared_ptr<TransCoder> transCoder, int32_t fdDst)
{
    int32_t ret = CheckStateMachine(CjAVTransCoderOpt::SET_FD);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    
    fdDst_ = fdDst;
    ret = transCoder->SetOutputFile(fdDst);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, GetReturnRet(ret));
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::OnProgressUpdate(int64_t callbackId)
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }

    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->SaveCallbackReference(CJAVTranscoderEvent::EVENT_PROGRESS_UPDATE, callbackId);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::OffProgressUpdate()
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->CancelCallbackReference(CJAVTranscoderEvent::EVENT_PROGRESS_UPDATE);
    return MSERR_EXT_API9_OK;
}


int32_t CJAVTranscoder::OnComplete(int64_t callbackId)
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }

    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->SaveCallbackReference(CJAVTranscoderEvent::EVENT_COMPLETE, callbackId);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::OffComplete()
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->CancelCallbackReference(CJAVTranscoderEvent::EVENT_COMPLETE);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::OnError(int64_t callbackId)
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }

    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->SaveCallbackReference(CJAVTranscoderEvent::EVENT_ERROR, callbackId);
    return MSERR_EXT_API9_OK;
}

int32_t CJAVTranscoder::OffError()
{
    if (transCoderCb_ == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto cjCb = std::static_pointer_cast<CJAVTranscoderCallback>(transCoderCb_);
    cjCb->CancelCallbackReference(CJAVTranscoderEvent::EVENT_ERROR);
    return MSERR_EXT_API9_OK;
}
}
}