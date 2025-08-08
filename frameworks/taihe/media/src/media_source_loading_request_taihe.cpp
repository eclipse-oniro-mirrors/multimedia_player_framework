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

#include "media_source_loading_request_taihe.h"
#include "media_log.h"
#include "media_dfx.h"
#include "media_taihe_utils.h"

using namespace ANI::Media;
using namespace OHOS::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "MediaSourceLoadingRequestTaihe"};
}

namespace ANI::Media {
MediaSourceLoadingRequestImpl::MediaSourceLoadingRequestImpl(uint64_t requestId)
{
    request_ = RequestContainer::GetInstance().Find(requestId);
    CHECK_AND_RETURN_LOG(request_ != nullptr, "failed to getRequest");
    RequestContainer::GetInstance().Erase(requestId);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor success", FAKE_POINTER(this));
}

string MediaSourceLoadingRequestImpl::GetUrl()
{
    MediaTrace trace("MediaSourceLoadingRequestTaihe::GetUrl");
    MEDIA_LOGI("GetUrl In");
    return MediaTaiheUtils::ToTaiheString(request_->GetUrl().c_str());
}

optional<map<string, string>> MediaSourceLoadingRequestImpl::GetHeader()
{
    MediaTrace trace("MediaSourceLoadingRequestTaihe::GetHeader");
    MEDIA_LOGI("GetHeader In");
    std::map<std::string, std::string> header = request_->GetHeader();
    if (header.empty()) {
        return optional<map<string, string>>(std::nullopt);
    }
    map<string, string> taiheHeader;
    for (const auto& [key, value] : header) {
        taihe::string taiheKey(key);
        taihe::string taiheValue(value);
        taiheHeader.emplace(taiheKey, taiheValue);
    }
    return optional<map<string, string>>(std::in_place_t{}, taiheHeader);
}

optional<int32_t> MediaSourceLoadingRequestImpl::RespondData(int64_t uuid, int64_t offset, array_view<uint8_t> buffer)
{
    MediaTrace trace("MediaSourceLoadingRequestTaihe::respondData");
    MEDIA_LOGI("respondData In");
    uint8_t *arrayBuffer = buffer.data();
    size_t arrayBufferSize = buffer.size();

    auto bufferInner = std::make_shared<AVSharedMemoryBase>(static_cast<int32_t>(arrayBufferSize),
        AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    CHECK_AND_RETURN_RET_LOG(bufferInner != nullptr, optional<int32_t>(std::nullopt), "get buffer fail");
    bufferInner->Init();
    bufferInner->Write(static_cast<uint8_t *>(arrayBuffer), arrayBufferSize);
    MEDIA_LOGI("respondData getSize: %{public}d", bufferInner->GetSize());
    int32_t res = request_->RespondData(uuid, offset, bufferInner);
    return optional<int32_t>(std::in_place_t{}, res);
}

void MediaSourceLoadingRequestImpl::RespondHeader(int64_t uuid, optional_view<map<string, string>> header,
    optional_view<string> redirectUrl)
{
    MediaTrace trace("MediaSourceLoadingRequestTaihe::respondHeader");
    MEDIA_LOGI("respondHeader In");
    std::map<std::string, std::string> headerInner {};
    if (header.has_value()) {
        for (const auto& [key, value] : *header) {
            std::string strKey(key);
            std::string strValue(value);
            headerInner.emplace(strKey, strValue);
        }
    }
    std::string redirectUrlStr;
    if (redirectUrl.has_value()) {
        redirectUrlStr = static_cast<std::string>(redirectUrl.value());
    }
    request_->RespondHeader(uuid, headerInner, redirectUrlStr);
    MEDIA_LOGI("respondHeader redirectUrl %{private}s", redirectUrlStr.c_str());
}

void MediaSourceLoadingRequestImpl::FinishLoading(int64_t uuid, LoadingRequestError state)
{
    MediaTrace trace("MediaSourceLoadingRequestTaihe::finishLoading");
    MEDIA_LOGI("finishLoading In");
    int32_t requestError = state.get_value();
    request_->FinishLoading(uuid, requestError);
}

::ohos::multimedia::media::MediaSourceLoadingRequest MediaSourceLoadingRequestImpl::CreateLoadingRequest(
    std::shared_ptr<LoadingRequest> request)
{
    MediaTrace trace("MediaSourceLoadingRequestImpl::CreateLoadingRequest");
    MEDIA_LOGD("CreateLoadingRequest >>");
    RequestContainer::GetInstance().Insert(request->GetUniqueId(), request);
    return taihe::make_holder<MediaSourceLoadingRequestImpl,
        ::ohos::multimedia::media::MediaSourceLoadingRequest>(request->GetUniqueId());
}
} // namespace ANI::Media