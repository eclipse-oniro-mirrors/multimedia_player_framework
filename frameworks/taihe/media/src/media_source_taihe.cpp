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

#include "media_source_taihe.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_taihe_utils.h"

using namespace ANI::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "MediaSourceTaihe"};
constexpr uint32_t MAX_MEDIA_STREAM_ARRAY_LENGTH = 10;
}

namespace ANI::Media {

MediaSourceImpl::MediaSourceImpl(string_view url, optional_view<map<string, string>> headers)
{
    mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (mediaSource_ == nullptr) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithUrl GetMediaSource fail");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithUrl GetMediaSource fail");
        return;
    }
    mediaSource_->url = static_cast<std::string>(url);
    if (headers.has_value()) {
        for (const auto& [key, value] : *headers) {
            std::string strKey(key);
            std::string strValue(value);
            mediaSource_->header.emplace(strKey, strValue);
        }
    }
}

MediaSourceImpl::MediaSourceImpl(array_view<::ohos::multimedia::media::MediaStream> streams)
{
    if (streams.size() == 0) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithStreamData GetMediaSource fail Array<MediaStream> is 0");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithUrl GetMediaSource fail");
        return;
    }
    if (streams.size() > MAX_MEDIA_STREAM_ARRAY_LENGTH) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithStreamData GetMediaSource fail Array<MediaStream> is too long");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithStreamData GetMediaSource fail");
        return;
    }
    mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (mediaSource_ == nullptr) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithStreamData GetMediaSource fail");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithStreamData GetMediaSource fail");
        return;
    }
    for (uint32_t i = 0; i < streams.size(); i++) {
        AVPlayMediaStreamTmp mediaStream;
        mediaStream.url = static_cast<std::string>(streams[i].url);
        mediaStream.width = static_cast<uint32_t>(streams[i].width);
        mediaStream.height = static_cast<uint32_t>(streams[i].height);
        mediaStream.bitrate = static_cast<uint32_t>(streams[i].bitrate);
        MEDIA_LOGI("url=%{private}s width=%{public}d height=%{public}d bitrate=%{public}d",
            mediaStream.url.c_str(),
            mediaStream.width,
            mediaStream.height,
            mediaStream.bitrate);
        mediaSource_->AddAVPlayMediaStreamTmp(mediaStream);
    }
    MEDIA_LOGD("TaiheCreateMediaSourceWithStreamData get mediaStreamVec length=%{public}lu", streams.size());
}

int64_t MediaSourceImpl::GetImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithUrl(string_view url,
    optional_view<map<string, string>> headers)
{
    MEDIA_LOGD("TaiheCreateMediaSourceWithUrl In");
    auto res = taihe::make_holder<MediaSourceImpl, ::ohos::multimedia::media::MediaSource>(url, headers);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create MediaSource failed!");
        taihe::reset_error();
        return optional<::ohos::multimedia::media::MediaSource>(std::nullopt);
    }
    return optional<::ohos::multimedia::media::MediaSource>(std::in_place, res);
}

optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithStreamData(
    array_view<::ohos::multimedia::media::MediaStream> streams)
{
    MEDIA_LOGD("TaiheCreateMediaSourceWithStreamData In");
    auto res = taihe::make_holder<MediaSourceImpl, ::ohos::multimedia::media::MediaSource>(streams);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create MediaSource failed!");
        taihe::reset_error();
        return optional<::ohos::multimedia::media::MediaSource>(std::nullopt);
    }
    return optional<::ohos::multimedia::media::MediaSource>(std::in_place, res);
}

std::shared_ptr<AVMediaSourceTmp> MediaSourceImpl::GetMediaSource(weak::MediaSource mediaSource)
{
    MediaSourceImpl* mediaSourceImpl = reinterpret_cast<MediaSourceImpl*>(mediaSource->GetImplPtr());
    if (mediaSourceImpl == nullptr) {
        MEDIA_LOGE("Failed to get MediaSourceImpl");
        return nullptr;
    }
    return mediaSourceImpl->mediaSource_;
}

std::shared_ptr<AVMediaSourceTmp> MediaSourceImpl::GetMediaSource(MediaSourceImpl *mediaSourceImpl)
{
    return mediaSourceImpl->mediaSource_;
}

std::shared_ptr<MediaSourceLoaderCallback> MediaSourceImpl::GetSourceLoader(weak::MediaSource mediaSource)
{
    MediaSourceImpl* mediaSourceImpl = reinterpret_cast<MediaSourceImpl*>(mediaSource->GetImplPtr());
    if (mediaSourceImpl == nullptr) {
        MEDIA_LOGE("Failed to get MediaSourceImpl");
        return nullptr;
    }
    return mediaSourceImpl->mediaSourceLoaderCb_;
}

void MediaSourceImpl::SetMimeType(::ohos::multimedia::media::AVMimeTypes mimeType)
{
    MEDIA_LOGI("TaiheSetMimeType In");
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(this);

    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return;
    }
    std::string mimeTypeStr = static_cast<std::string>(mimeType.get_value());
    if (mimeTypeStr.empty()) {
        MEDIA_LOGE("MimeType is empty.");
        return;
    }
    mediaSource->SetMimeType(mimeTypeStr);
}

void MediaSourceImpl::SetMediaResourceLoaderDelegate(::ohos::multimedia::media::MediaSourceLoader const& resourceLoader)
{
    MediaTrace trace("MediaSourceTaihe::SetMediaResourceLoaderDelegate");
    MEDIA_LOGI("TaiheSetMediaResourceLoaderDelegate In");
    mediaSourceLoaderCb_ = std::make_shared<MediaSourceLoaderCallback>();
    CHECK_AND_RETURN_LOG(mediaSourceLoaderCb_ != nullptr, "Cb_ is nullptr");
    ani_env *env = get_env();
    std::shared_ptr<taihe::callback<int64_t(ohos::multimedia::media::weak::MediaSourceLoadingRequest)>>
        taiheCallbackOpen = std::make_shared<taihe::callback<
        int64_t(ohos::multimedia::media::weak::MediaSourceLoadingRequest)>>(resourceLoader.open);
    std::shared_ptr<uintptr_t> cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallbackOpen);

    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    mediaSourceLoaderCb_->SaveCallbackReference(FunctionName::SOURCE_OPEN, autoRef);

    std::shared_ptr<taihe::callback<void(int64_t, int64_t, int64_t)>> taiheCallbackRead =
        std::make_shared<taihe::callback<void(int64_t, int64_t, int64_t)>>(resourceLoader.read);
    cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallbackRead);
    autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    mediaSourceLoaderCb_->SaveCallbackReference(FunctionName::SOURCE_READ, autoRef);

    std::shared_ptr<taihe::callback<void(int64_t)>> taiheCallbackClose =
        std::make_shared<taihe::callback<void(int64_t)>>(resourceLoader.close);
    cacheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallbackClose);
    autoRef = std::make_shared<AutoRef>(env, cacheCallback);
    mediaSourceLoaderCb_->SaveCallbackReference(FunctionName::SOURCE_CLOSE, autoRef);
    MEDIA_LOGI("TaiheSetMediaResourceLoaderDelegate Out");
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateMediaSourceWithUrl(CreateMediaSourceWithUrl);
TH_EXPORT_CPP_API_CreateMediaSourceWithStreamData(CreateMediaSourceWithStreamData);