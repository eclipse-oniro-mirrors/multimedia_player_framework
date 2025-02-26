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

#include "loading_request_impl.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "LoadingRequestImpl" };
static std::atomic<uint64_t> g_uniqueRequestID = 0;
}

namespace OHOS {
namespace Media {
LoadingRequestImpl::LoadingRequestImpl(const std::shared_ptr<IMediaSourceLoadingRequest> &loadingRequest,
    std::string url, std::map<std::string, std::string> header)
    : loadingRequestCallback_(loadingRequest), url_(url), header_(header)
{
    MEDIA_LOGD("LoadingRequestImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    uniqueId_ = g_uniqueRequestID.fetch_add(1, std::memory_order_relaxed);
}

LoadingRequestImpl::~LoadingRequestImpl()
{
    MEDIA_LOGD("LoadingRequestImpl:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LoadingRequestImpl::RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem)
{
    CHECK_AND_RETURN_RET_LOG(loadingRequestCallback_ != nullptr, MSERR_INVALID_VAL,
        "loadingRequestCallback_ not exist");
    return loadingRequestCallback_->RespondData(uuid, offset, mem);
}

int32_t LoadingRequestImpl::RespondHeader(int64_t uuid,
    std::map<std::string, std::string> header, std::string redirectUrl)
{
    CHECK_AND_RETURN_RET_LOG(loadingRequestCallback_ != nullptr, MSERR_INVALID_VAL,
        "loadingRequestCallback_ not exist");
    return loadingRequestCallback_->RespondHeader(uuid, header, redirectUrl);
}

int32_t LoadingRequestImpl::FinishLoading(int64_t uuid, int32_t requestedError)
{
    CHECK_AND_RETURN_RET_LOG(loadingRequestCallback_ != nullptr, MSERR_INVALID_VAL,
        "loadingRequestCallback_ not exist");
    return loadingRequestCallback_->FinishLoading(uuid, static_cast<LoadingRequestError>(requestedError));
}

uint64_t LoadingRequestImpl::GetUniqueId()
{
    return uniqueId_;
}

std::string LoadingRequestImpl::GetUrl()
{
    return url_;
}

std::map<std::string, std::string> LoadingRequestImpl::GetHeader()
{
    return header_;
}
} // namespace Media
} // namespace OHOS