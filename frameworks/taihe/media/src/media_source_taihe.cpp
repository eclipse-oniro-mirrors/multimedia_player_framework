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
using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

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
    mediaSource_->SetID(AVMediaSourceTmp::GenerateUniqueId());
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
    mediaSource_->SetID(AVMediaSourceTmp::GenerateUniqueId());
    MEDIA_LOGD("TaiheCreateMediaSourceWithStreamData get mediaStreamVec length=%{public}zu", streams.size());
}

MediaSourceImpl::MediaSourceImpl(::ohos::multimedia::media::AVFileDescriptor fd)
{
    mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (mediaSource_ == nullptr) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithFd GetMediaSource fail");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithFd GetMediaSource fail");
        return;
    }
    mediaSource_->fd = fd;
    int64_t offset = fd.offset.has_value() ? fd.offset.value() : 0;
    int64_t length = fd.length.has_value() ? fd.length.value() : 0;
    MEDIA_LOGD("TaiheCreateMediaSourceWithFd fd: %{public}d, offset: %{public}" PRIi64 ", length: %{public}" PRIi64,
        mediaSource_->fd.fd, offset, length);
    mediaSource_->SetID(AVMediaSourceTmp::GenerateUniqueId());
}
 
MediaSourceImpl::MediaSourceImpl(::ohos::multimedia::media::AVDataSrcDescriptor dataSrc)
{
    mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (mediaSource_ == nullptr) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithDataSource GetMediaSource fail");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithDataSource GetMediaSource fail");
        return;
    }
    mediaSource_->dataSrc.fileSize = dataSrc.fileSize;
    auto callbackPtr = std::make_shared<DataSrcCallback>(dataSrc.callback);
    mediaSource_->dataSrc.callback = std::reinterpret_pointer_cast<uintptr_t>(callbackPtr);
    MEDIA_LOGD("TaiheCreateMediaSourceWithDataSource fileSize: %{public}" PRId64, mediaSource_->dataSrc.fileSize);
    mediaSource_->SetID(AVMediaSourceTmp::GenerateUniqueId());
}

MediaSourceImpl::MediaSourceImpl(string_view directoryPath)
{
    mediaSource_ = std::make_shared<AVMediaSourceTmp>();
    if (mediaSource_ == nullptr) {
        MEDIA_LOGE("TaiheCreateMediaSourceWithDirectory GetMediaSource fail");
        MediaTaiheUtils::ThrowExceptionError("TaiheCreateMediaSourceWithDirectory GetMediaSource fail");
        return;
    }
    mediaSource_->directoryPath = static_cast<std::string>(directoryPath);
    mediaSource_->SetID(AVMediaSourceTmp::GenerateUniqueId());
    MEDIA_LOGD("TaiheCreateMediaSourceWithDirectory path=%{public}s", mediaSource_->directoryPath.c_str());
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

optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithFd(
    ::ohos::multimedia::media::AVFileDescriptor fd)
{
    MEDIA_LOGD("TaiheCreateMediaSourceWithFd In");
    auto res = taihe::make_holder<MediaSourceImpl, ::ohos::multimedia::media::MediaSource>(fd);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create MediaSource failed!");
        taihe::reset_error();
        return optional<::ohos::multimedia::media::MediaSource>(std::nullopt);
    }
    return optional<::ohos::multimedia::media::MediaSource>(std::in_place, res);
}
 
optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithDataSource(
    ::ohos::multimedia::media::AVDataSrcDescriptor dataSrc)
{
    MEDIA_LOGD("TaiheCreateMediaSourceWithDataSource In");
    auto res = taihe::make_holder<MediaSourceImpl, ::ohos::multimedia::media::MediaSource>(dataSrc);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create MediaSource failed!");
        taihe::reset_error();
        return optional<::ohos::multimedia::media::MediaSource>(std::nullopt);
    }
    return optional<::ohos::multimedia::media::MediaSource>(std::in_place, res);
}

optional<::ohos::multimedia::media::MediaSource> CreateMediaSourceWithDirectorySync(string_view directoryPath)
{
    MEDIA_LOGD("TaiheCreateMediaSourceWithDirectory In");
    auto res = taihe::make_holder<MediaSourceImpl, ::ohos::multimedia::media::MediaSource>(directoryPath);
    if (taihe::has_error()) {
        MEDIA_LOGE("Create MediaSource failed!");
        taihe::reset_error();
        return optional<::ohos::multimedia::media::MediaSource>(std::nullopt);
    }
    return optional<::ohos::multimedia::media::MediaSource>(std::in_place, res);
}

std::shared_ptr<AVMediaSourceTmp> MediaSourceImpl::GetMediaSource(weak::MediaSource mediaSource)
{
    if (mediaSource.is_error()) {
        MEDIA_LOGE("GetMediaSource: mediaSource weak reference is invalid");
        return nullptr;
    }
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
    if (mediaSource.is_error()) {
        MEDIA_LOGE("GetSourceLoader: mediaSource weak reference is invalid");
        return nullptr;
    }
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

std::string MediaSourceImpl::GetID()
{
    MEDIA_LOGI("TaiheGetID In");
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(this);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return "";
    }
    std::string id = mediaSource->GetID();
    MEDIA_LOGI("TaiheGetID Out, id=%{public}s", id.c_str());
    return id;
}

void MediaSourceImpl::SetRetrieveKey(string_view key)
{
    MEDIA_LOGI("TaiheSetRetrieveKey In");
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(this);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return;
    }
    mediaSource->retrieveKey = static_cast<std::string>(key);
}

void MediaSourceImpl::SetTrackSelectionFilter(TrackSelectionFilter filter)
{
    MEDIA_LOGI("TaiheSetTrackSelectionFilter In");
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(this);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return;
    }
    AVPlayTrackSelectionFilter avfilter;
    auto assignIfPresent = [](auto& dest, const auto& src) {
        if (src.has_value()) dest = src.value();
    };
    assignIfPresent(avfilter.maxVideoBitrate, filter.maxVideoBitrate);
    assignIfPresent(avfilter.minVideoBitrate, filter.minVideoBitrate);
    assignIfPresent(avfilter.maxVideoFrameRate, filter.maxVideoFrameRate);
    assignIfPresent(avfilter.minVideoFrameRate, filter.minVideoFrameRate);
    assignIfPresent(avfilter.maxAudioBitrate, filter.maxAudioBitrate);
    assignIfPresent(avfilter.minAudioBitrate, filter.minAudioBitrate);
    assignIfPresent(avfilter.maxAudioChannels, filter.maxAudioChannels);
    auto assignVec = [](auto& dest, const auto& src) {
        if (src.has_value() && !src.value().empty()) {
            dest = std::vector<std::string>(src.value().begin(), src.value().end());
        }
    };
    assignVec(avfilter.preferredVideoMimeTypes, filter.preferredVideoMimeTypes);
    assignVec(avfilter.preferredAudioMimeTypes, filter.preferredAudioMimeTypes);
    assignVec(avfilter.preferredAudioLanguages, filter.preferredAudioLanguages);
    assignVec(avfilter.preferredSubtitleLanguages, filter.preferredSubtitleLanguages);
    auto assignRes = [](auto& dest, const auto& src) {
        if (src.has_value()) {
            dest = std::make_pair(src.value().width.value_or(0), src.value().height.value_or(0));
        }
    };
    assignRes(avfilter.maxVideoResolution, filter.maxVideoResolution);
    assignRes(avfilter.minVideoResolution, filter.minVideoResolution);
    mediaSource->trackSelectionFilter = avfilter;
    mediaSource->hasTrackSelectionFilter = true;
    MEDIA_LOGI("TaiheSetTrackSelectionFilter Out");
}

optional<TrackSelectionFilter> MediaSourceImpl::GetTrackSelectionFilter()
{
    MEDIA_LOGI("TaiheGetTrackSelectionFilter In");
    std::shared_ptr<AVMediaSourceTmp> mediaSource = GetMediaSource(this);
    if (mediaSource == nullptr) {
        MEDIA_LOGE("Fail to get mediaSource instance.");
        return optional<TrackSelectionFilter>(std::nullopt);
    }
    if (!mediaSource->hasTrackSelectionFilter) {
        MEDIA_LOGE("TrackSelectionFilter not set.");
        return optional<TrackSelectionFilter>(std::nullopt);
    }
    TrackSelectionFilter filter;
    const auto& avfilter = mediaSource->trackSelectionFilter;
    auto assignOpt = [](auto& target, const auto& source) {
        if (source >= 0) {
            target = optional<std::decay_t<decltype(target.value())>>(std::in_place_t{}, source);
        }
    };
    assignOpt(filter.maxVideoBitrate, avfilter.maxVideoBitrate);
    assignOpt(filter.minVideoBitrate, avfilter.minVideoBitrate);
    assignOpt(filter.maxVideoFrameRate, avfilter.maxVideoFrameRate);
    assignOpt(filter.minVideoFrameRate, avfilter.minVideoFrameRate);
    assignOpt(filter.maxAudioBitrate, avfilter.maxAudioBitrate);
    assignOpt(filter.minAudioBitrate, avfilter.minAudioBitrate);
    assignOpt(filter.maxAudioChannels, avfilter.maxAudioChannels);
    auto assignRes = [](auto& target, const auto& source) {
        if (source.first >= 0 && source.second >= 0) {
            VideoSize vs;
            vs.width = optional<int32_t>(std::in_place_t{}, source.first);
            vs.height = optional<int32_t>(std::in_place_t{}, source.second);
            target = optional<VideoSize>(std::in_place_t{}, vs);
        }
    };
    assignRes(filter.maxVideoResolution, avfilter.maxVideoResolution);
    assignRes(filter.minVideoResolution, avfilter.minVideoResolution);
    auto assignArr = [](auto& target, const auto& source) {
        if (!source.empty()) {
            target = optional<array<string>>(std::in_place_t{},
                array<string>(copy_data_t{}, source.data(), source.size()));
        }
    };
    assignArr(filter.preferredVideoMimeTypes, avfilter.preferredVideoMimeTypes);
    assignArr(filter.preferredAudioMimeTypes, avfilter.preferredAudioMimeTypes);
    assignArr(filter.preferredAudioLanguages, avfilter.preferredAudioLanguages);
    assignArr(filter.preferredSubtitleLanguages, avfilter.preferredSubtitleLanguages);
    MEDIA_LOGI("TaiheGetTrackSelectionFilter Out");
    return optional<TrackSelectionFilter>(std::in_place_t{}, filter);
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateMediaSourceWithUrl(CreateMediaSourceWithUrl);
TH_EXPORT_CPP_API_CreateMediaSourceWithStreamData(CreateMediaSourceWithStreamData);
TH_EXPORT_CPP_API_CreateMediaSourceWithFd(CreateMediaSourceWithFd);
TH_EXPORT_CPP_API_CreateMediaSourceWithDataSource(CreateMediaSourceWithDataSource);
TH_EXPORT_CPP_API_CreateMediaSourceWithDirectorySync(CreateMediaSourceWithDirectorySync);
TH_EXPORT_CPP_API_CreateMediaSourceWithDirectoryWithAsyncCallback(CreateMediaSourceWithDirectorySync);
TH_EXPORT_CPP_API_CreateMediaSourceWithDirectoryRetPromise(CreateMediaSourceWithDirectorySync);