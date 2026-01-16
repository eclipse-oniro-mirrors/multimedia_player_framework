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
    std::lock_guard<std::mutex> lock(mutex_);
    HiviewDFX::HiTraceChain::SetId(traceId_);
    transCoderService_ = MediaServiceFactory::GetInstance().CreateTransCoderService();
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_NO_MEMORY, "failed to create transcoder service");
    return MSERR_OK;
}

TransCoderImpl::TransCoderImpl()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    traceId_ = HiviewDFX::HiTraceChain::Begin("TransCoderImpl", HITRACE_FLAG_DEFAULT);
}

TransCoderImpl::~TransCoderImpl()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(transCoderService_ != nullptr, "0x%{public}06" PRIXPTR " Inst destroy", FAKE_POINTER(this));
    (void)MediaServiceFactory::GetInstance().DestroyTransCoderService(transCoderService_);
    transCoderService_ = nullptr;
    HiviewDFX::HiTraceChain::End(traceId_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t TransCoderImpl::SetVideoEncoder(VideoCodecFormat encoder)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoEncoder in, encoder is %{public}d",
        FAKE_POINTER(this), encoder);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoEncoder(encoder);
}

int32_t TransCoderImpl::SetVideoSize(int32_t width, int32_t height)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoSize in, width is %{public}d, height is %{public}d",
        FAKE_POINTER(this), width, height);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoSize(width, height);
}

int32_t TransCoderImpl::SetVideoEncodingBitRate(int32_t bitRate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetVideoEncodingBitRate in, bitRate is %{public}d",
        FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetVideoEncodingBitRate(bitRate);
}

int32_t TransCoderImpl::SetColorSpace(TranscoderColorSpace colorSpaceFormat)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetColorSpace in, colorSpace is %{public}d",
        FAKE_POINTER(this), static_cast<int32_t>(colorSpaceFormat));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetColorSpace(colorSpaceFormat);
}

int32_t TransCoderImpl::SetEnableBFrame(bool enableBFrame)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetEnableBFrame in, enableBFrame is %{public}d",
        FAKE_POINTER(this), static_cast<int32_t>(enableBFrame));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetEnableBFrame(enableBFrame);
}

int32_t TransCoderImpl::SetAudioEncoder(AudioCodecFormat encoder)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetAudioEncoder in, encoder is %{public}d",
        FAKE_POINTER(this), encoder);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetAudioEncoder(encoder);
}

int32_t TransCoderImpl::SetAudioEncodingBitRate(int32_t bitRate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetAudioEncodingBitRate in, bitRate is %{public}d",
        FAKE_POINTER(this), bitRate);
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetAudioEncodingBitRate(bitRate);
}

int32_t TransCoderImpl::SetOutputFormat(OutputFormatType format)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetOutputFormat in, format is %{public}d",
        FAKE_POINTER(this), format);
    CHECK_AND_RETURN_RET_LOG(format != FORMAT_DEFAULT, MSERR_INVALID_VAL, "format is invalid");
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetOutputFormat(format);
}

int32_t TransCoderImpl::SetInputFile(int32_t fd, int64_t offset, int64_t size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetInputFile in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetInputFile(fd, offset, size);
}

int32_t TransCoderImpl::SetOutputFile(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetOutputFile in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetOutputFile(fd);
}

int32_t TransCoderImpl::SetTransCoderCallback(const std::shared_ptr<TransCoderCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " SetTransCoderCallback in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input callback is nullptr.");
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->SetTransCoderCallback(callback);
}

int32_t TransCoderImpl::Prepare()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Prepare in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Prepare();
}

int32_t TransCoderImpl::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Start in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Start();
}

int32_t TransCoderImpl::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Pause in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Pause();
}

int32_t TransCoderImpl::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Resume in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Resume();
}

int32_t TransCoderImpl::Cancel()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("TransCoderImpl:0x%{public}06" PRIXPTR " Cancel in", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(transCoderService_ != nullptr, MSERR_INVALID_OPERATION,
        "transcoder service does not exist..");
    return transCoderService_->Cancel();
}

int32_t TransCoderImpl::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
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
