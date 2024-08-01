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

#include "transcoder_impl.h"
#include <map>
#include "i_media_service.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "TransCoderImpl"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<TransCoder> TransCoderFactory::CreateTransCoder()
{
    std::shared_ptr<TransCoderImpl> impl = std::make_shared<TransCoderImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new TransCoderImpl");

    int32_t ret = impl->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init TransCoderImpl");
    return impl;
}

int32_t TransCoderImpl::Init()
{
    transCoderService_ = MediaServiceFactory::GetInstance().CreateTransCoderService();
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_NO_MEMORY, "failed to create transcoder service");
    return MSERR_OK;
}

TransCoderImpl::TransCoderImpl()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

TransCoderImpl::~TransCoderImpl()
{
    CHECK_AND_RETURN_LOG(transCoderService_ != nullptr, "0x%{public}06" PRIXPTR " Inst destroy", FAKE_POINTER(this));
    (void)MediaServiceFactory::GetInstance().DestroyTransCoderService(transCoderService_);
    transCoderService_ = nullptr;
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t TransCoderImpl::SetVideoEncoder(VideoCodecFormat encoder)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoEncoder in, encoder is %{public}d",
        FAKE_POINTER(this), encoder);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoEncoder(encoder);
}

int32_t TransCoderImpl::SetVideoSize(int32_t width, int32_t height)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoSize in, width is %{public}d, height is %{public}d",
        FAKE_POINTER(this), width, height);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoSize(width, height);
}

int32_t TransCoderImpl::SetVideoEncodingBitRate(int32_t bitRate)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoEncodingBitRate in, bitRate is %{public}d",
        FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoEncodingBitRate(bitRate);
}

int32_t TransCoderImpl::SetAudioEncoder(AudioCodecFormat encoder)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetAudioEncoder in, encoder is %{public}d",
        FAKE_POINTER(this), encoder);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetAudioEncoder(encoder);
}

int32_t TransCoderImpl::SetAudioEncodingBitRate(int32_t bitRate)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetAudioEncodingBitRate in, bitRate is %{public}d",
        FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetAudioEncodingBitRate(bitRate);
}

int32_t TransCoderImpl::SetOutputFormat(OutputFormatType format)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetOutputFormat in, format is %{public}d",
        FAKE_POINTER(this), format);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetOutputFormat(format);
}

int32_t TransCoderImpl::SetInputFile(int32_t fd, int64_t offset, int64_t size)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetInputFile in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetInputFile(fd, offset, size);
}

int32_t TransCoderImpl::SetOutputFile(int32_t fd)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetOutputFile in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetOutputFile(fd);
}

int32_t TransCoderImpl::SetTransCoderCallback(const std::shared_ptr<TransCoderCallback> &callback)
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetTransCoderCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input callback is nullptr.");
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetTransCoderCallback(callback);
}

int32_t TransCoderImpl::Prepare()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Prepare in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Prepare();
}

int32_t TransCoderImpl::Start()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Start in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Start();
}

int32_t TransCoderImpl::Pause()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Pause in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Pause();
}

int32_t TransCoderImpl::Resume()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Resume in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Resume();
}

int32_t TransCoderImpl::Cancel()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Cancel in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Cancel();
}

int32_t TransCoderImpl::Release()
{
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Release in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    (void)transCoderService_->Release();
    (void)MediaServiceFactory::GetInstance().DestroyTransCoderService(transCoderService_);
    transCoderService_ = nullptr;
    return MSERR_OK;
}

} // namespace Media
} // namespace OHOS
