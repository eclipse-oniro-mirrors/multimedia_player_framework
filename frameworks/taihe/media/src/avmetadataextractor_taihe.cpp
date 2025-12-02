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

#include "avmetadataextractor_taihe.h"
#include "media_log.h"
#include "pixel_map_taihe.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "image_source.h"
#include "media_taihe_utils.h"

using namespace ANI::Media;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVMetadataExtractorTaihe"};
}
namespace ANI::Media {

AVMetadataExtractorImpl::AVMetadataExtractorImpl() {}

AVMetadataExtractorImpl::AVMetadataExtractorImpl(std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper)
{
    helper_ = avMetadataHelper;
}

optional<AVFileDescriptor> AVMetadataExtractorImpl::GetFdSrc()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractor::get fd");
    MEDIA_LOGI("TaiheGetAVFileDescriptor In");
    AVFileDescriptor fdSrc;
    fdSrc.fd = fileDescriptor_.fd;
    fdSrc.offset = optional<int64_t>(std::in_place_t{}, fileDescriptor_.offset);
    fdSrc.length = optional<int64_t>(std::in_place_t{}, fileDescriptor_.length);
    MEDIA_LOGI("TaiheGetAVFileDescriptor Out");
    return optional<AVFileDescriptor>(std::in_place_t{}, fdSrc);
}

void AVMetadataExtractorImpl::SetFdSrc(optional_view<AVFileDescriptor> fdSrc)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::set fd");
    MEDIA_LOGI("TaiheSetAVFileDescriptor In");
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_IDLE) {
        MEDIA_LOGE("Has set source once, unsupport set again");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("Invalid AVMetadataExtractorTaihe.");
        return;
    }
    if (fdSrc.has_value()) {
        fileDescriptor_.fd = fdSrc.value().fd;
        if (fdSrc.value().offset.has_value()) {
            fileDescriptor_.offset = fdSrc.value().offset.value();
        } else {
            fileDescriptor_.offset = 0;
        }
        if (fdSrc.value().length.has_value()) {
            fileDescriptor_.length = fdSrc.value().length.value();
        } else {
            fileDescriptor_.length = -1;
        }
    }
    auto res = helper_->SetSource(fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    state_ = res == OHOS::Media::MSERR_OK ?
        OHOS::Media::HelperState::HELPER_STATE_RUNNABLE : OHOS::Media::HelperState::HELPER_ERROR;
    MEDIA_LOGI("TaiheSetAVFileDescriptor Out");
    return;
}

optional<AVDataSrcDescriptor> AVMetadataExtractorImpl::GetDataSrc()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::set dataSrc");
    MEDIA_LOGI("TaiheGetDataSrc In");
    CHECK_AND_RETURN_RET_LOG(dataSrcCb_ != nullptr,
        optional<AVDataSrcDescriptor>(std::nullopt), "failed to check dataSrcCb_");

    int64_t fileSize;
    (void)dataSrcCb_->GetSize(fileSize);
    const std::string callbackName = "readAt";
    std::shared_ptr<uintptr_t> callback;
    int32_t ret = dataSrcCb_->GetCallback(callbackName, callback);
    CHECK_AND_RETURN_RET_LOG(ret == OHOS::Media::MSERR_OK,
        optional<AVDataSrcDescriptor>(std::nullopt), "failed to GetCallback");

    auto cacheCallback = std::reinterpret_pointer_cast<OHOS::Media::DataSrcCallback>(callback);
    AVDataSrcDescriptor fdSrc = AVDataSrcDescriptor{std::move(fileSize), std::move(*cacheCallback)};
    MEDIA_LOGI("TaiheGetDataSrc Out");
    return optional<AVDataSrcDescriptor>(std::in_place_t{}, fdSrc);
}

void AVMetadataExtractorImpl::SetUrlSource(::taihe::string_view url, optional_view<map<string, string>> header)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::setUrlSource");
    MEDIA_LOGI("TaiheSetUrlSource In");

    if (state_ != OHOS::Media::HelperState::HELPER_STATE_IDLE) {
        MEDIA_LOGE("Has set source once, unsupport set again");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("Invalid AVMetadataExtractorTaihe.");
        return;
    }

    std::string url_(url);
    std::map<std::string, std::string> header_;
    if (header.has_value()) {
        for (const auto& pair : header.value()) {
            header_[std::string(pair.first)] = std::string(pair.second);
        }
    }
    auto res = helper_->SetUrlSource(url_, header_);
    if (res == OHOS::Media::MSERR_OK) {
        state_ = OHOS::Media::HelperState::HELPER_STATE_RUNNABLE;
    } else {
        state_ = OHOS::Media::HelperState::HELPER_ERROR;
    }
    helper_->SetAVMetadataCaller(OHOS::Media::AVMetadataCaller::AV_METADATA_EXTRACTOR);
    MEDIA_LOGI("TaiheSetUrlSource Out");
}

void AVMetadataExtractorImpl::SetDataSrc(optional_view<AVDataSrcDescriptor> dataSrc)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::set dataSrc");
    MEDIA_LOGI("TaiheSetDataSrc In");

    if (state_ != OHOS::Media::HelperState::HELPER_STATE_IDLE) {
        MEDIA_LOGE("Has set source once, unsupport set again");
        return;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("Invalid AVMetadataExtractorTaihe.");
        return;
    }
    ani_env *env = taihe::get_env();
    if (dataSrc.has_value()) {
        dataSrcDescriptor_.fileSize = dataSrc.value().fileSize;
        if (!(dataSrcDescriptor_.fileSize >= -1 && dataSrcDescriptor_.fileSize != 0)) {
            return;
        }
        MEDIA_LOGI("Recvive filesize is %{public}" PRId64 "", dataSrcDescriptor_.fileSize);
        dataSrcCb_ = std::make_shared<OHOS::Media::HelperDataSourceCallback>(env, dataSrcDescriptor_.fileSize);
        auto callbackPtr = std::make_shared<OHOS::Media::DataSrcCallback>(dataSrc.value().callback);
        std::shared_ptr<uintptr_t> callback = std::reinterpret_pointer_cast<uintptr_t>(callbackPtr);
        dataSrcDescriptor_.callback = callback;
        std::shared_ptr<AutoRef> autoRef =
            std::make_shared<AutoRef>(env, dataSrcDescriptor_.callback);
        const std::string callbackName = "readAt";
        dataSrcCb_->SaveCallbackReference(callbackName, autoRef);
        auto res = helper_->SetSource(dataSrcCb_);
        state_ = res == OHOS::Media::MSERR_OK ?
            OHOS::Media::HelperState::HELPER_STATE_RUNNABLE : OHOS::Media::HelperState::HELPER_ERROR;
        MEDIA_LOGI("TaiheSetDataSrc Out");
    }
}

void AVMetadataExtractorImpl::SetDefaultMetadataProperty(AVMetadata &res)
{
    res.album = optional<string>(std::nullopt);
    res.albumArtist = optional<string>(std::nullopt);
    res.artist = optional<string>(std::nullopt);
    res.author = optional<string>(std::nullopt);
    res.dateTime = optional<string>(std::nullopt);
    res.dateTimeFormat = optional<string>(std::nullopt);
    res.composer = optional<string>(std::nullopt);
    res.duration = optional<string>(std::nullopt);
    res.genre = optional<string>(std::nullopt);
    res.hasAudio = optional<string>(std::nullopt);
    res.hasVideo = optional<string>(std::nullopt);
    res.mimeType = optional<string>(std::nullopt);
    res.trackCount = optional<string>(std::nullopt);
    res.sampleRate = optional<string>(std::nullopt);
    res.title = optional<string>(std::nullopt);
    res.videoHeight = optional<string>(std::nullopt);
    res.videoWidth = optional<string>(std::nullopt);
    res.videoOrientation = optional<string>(std::nullopt);
    res.hdrType = optional<HdrType>(std::nullopt);
    res.location = optional<Location>(std::nullopt);
    res.customInfo = optional<map<string, string>>(std::nullopt);
}

bool AVMetadataExtractorImpl::SetPropertyByType(AVMetadata &res, std::shared_ptr<OHOS::Media::Meta> metadata,
    std::string key)
{
    CHECK_AND_RETURN_RET(metadata != nullptr, false);
    CHECK_AND_RETURN_RET(metadata->Find(key) != metadata->end(), false);

    using StringMember = optional<string> AVMetadata::*;
    const std::unordered_map<std::string, StringMember> stringKeyMap = {
        {"album", &AVMetadata::album},
        {"albumArtist", &AVMetadata::albumArtist},
        {"artist", &AVMetadata::artist},
        {"author", &AVMetadata::author},
        {"dateTime", &AVMetadata::dateTime},
        {"dateTimeFormat", &AVMetadata::dateTimeFormat},
        {"composer", &AVMetadata::composer},
        {"duration", &AVMetadata::duration},
        {"genre", &AVMetadata::genre},
        {"hasAudio", &AVMetadata::hasAudio},
        {"hasVideo", &AVMetadata::hasVideo},
        {"mimeType", &AVMetadata::mimeType},
        {"trackCount", &AVMetadata::trackCount},
        {"sampleRate", &AVMetadata::sampleRate},
        {"title", &AVMetadata::title},
        {"videoHeight", &AVMetadata::videoHeight},
        {"videoWidth", &AVMetadata::videoWidth},
        {"videoOrientation", &AVMetadata::videoOrientation}
    };
    bool ret = true;
    OHOS::Media::AnyValueType type = metadata->GetValueType(key);
    if (type == OHOS::Media::AnyValueType::STRING) {
        std::string sValue;
        ret = metadata->GetData(key, sValue);
        CHECK_AND_RETURN_RET_LOG(ret, ret, "GetData failed, key %{public}s", key.c_str());
        auto it = stringKeyMap.find(key);
        if (it != stringKeyMap.end()) {
            res.*(it->second) = optional<string>(std::in_place_t{}, sValue);
        }
    } else if (type == OHOS::Media::AnyValueType::INT32_T) {
        int32_t value;
        ret = metadata->GetData(key, value);
        CHECK_AND_RETURN_RET_LOG(ret, ret, "GetData failed, key %{public}s", key.c_str());
        if (key == "hdrType") {
            HdrType::key_t key;
            MediaTaiheUtils::GetEnumKeyByValue<HdrType>(value, key);
            res.hdrType = optional<HdrType>(std::in_place_t{}, HdrType(key));
        }
    } else {
        MEDIA_LOGE("not supported value type");
    }
    return true;
}

void AVMetadataExtractorImpl::SetMetadataProperty(std::shared_ptr<OHOS::Media::Meta> metadata, AVMetadata &res)
{
    Location loc;
    map<string, string> customInfo;
    for (const auto &key : OHOS::Media::g_Metadata) {
        if (metadata->Find(key) == metadata->end()) {
            MEDIA_LOGE("failed to find key: %{public}s", key.c_str());
            continue;
        }
        MEDIA_LOGE("success to find key: %{public}s", key.c_str());
        if (key == "latitude" || key == "longitude") {
            int32_t value;
            CHECK_AND_CONTINUE_LOG(metadata->GetData(key, value), "GetData failed, key %{public}s", key.c_str());
            if (key == "latitude") {
                loc.latitude = value;
            } else {
                loc.longitude = value;
            }
            res.location = optional<Location>(std::in_place_t{}, loc);
            continue;
        }
        if (key == "customInfo") {
            std::shared_ptr<OHOS::Media::Meta> customData = std::make_shared<OHOS::Media::Meta>();
            CHECK_AND_CONTINUE_LOG(metadata->GetData(key, customData), "GetData failed, key %{public}s", key.c_str());
            CHECK_AND_CONTINUE_LOG(customData != nullptr, "customData is nullptr");
            for (auto iter = customData->begin(); iter != customData->end(); ++iter) {
                OHOS::Media::AnyValueType type = customData->GetValueType(iter->first);
                CHECK_AND_CONTINUE_LOG(type == OHOS::Media::AnyValueType::STRING, "key is not string");
                std::string sValue;
                CHECK_AND_CONTINUE_LOG(customData->GetData(iter->first, sValue), "GetData failed, key %{public}s",
                    iter->first.c_str());
                customInfo.emplace(iter->first, sValue);
            }
            res.customInfo = optional<map<string, string>>(std::in_place_t{}, customInfo);
            continue;
        }
        CHECK_AND_CONTINUE_LOG(SetPropertyByType(res, metadata, key),
            "SetProperty failed, key: %{public}s", key.c_str());
    }
}

optional<AVMetadata> AVMetadataExtractorImpl::FetchMetadataSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::FetchMetadataSync");
    MEDIA_LOGI("FetchMetadataSync In");
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchMetadata, please set source.");
        return optional<AVMetadata>(std::nullopt);
    }
    CHECK_AND_RETURN_RET_LOG(helper_ != nullptr, optional<AVMetadata>(std::nullopt), "Invalid promiseCtx.");
    std::shared_ptr<OHOS::Media::Meta> metadata = helper_->GetAVMetadata();
    if (metadata == nullptr) {
        MEDIA_LOGE("ResolveMetadata AVMetadata is nullptr");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "ResolveMetadata fail, metadata is null!");
        return optional<AVMetadata>(std::nullopt);
    }
    AVMetadata res;
    SetDefaultMetadataProperty(res);
    SetMetadataProperty(metadata, res);
    return optional<AVMetadata>(std::in_place_t{}, res);
}

optional<AVMetadataExtractor> CreateAVMetadataExtractorSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractor::CreateAVMetadataExtractor");
    MEDIA_LOGI("TaiheCreateAVMetadataExtractor In");

    std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper =
        OHOS::Media::AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, optional<AVMetadataExtractor>(std::nullopt),
        "failed to CreateMetadataHelper");
    MEDIA_LOGI("TaiheCreateAVMetadataExtractor Out");
    auto res = make_holder<AVMetadataExtractorImpl, AVMetadataExtractor>(avMetadataHelper);
    return optional<AVMetadataExtractor>(std::in_place_t{}, res);
}

static std::unique_ptr<OHOS::Media::PixelMap> ConvertMemToPixelMap(
    std::shared_ptr<OHOS::Media::AVSharedMemory> sharedMemory)
{
    CHECK_AND_RETURN_RET_LOG(sharedMemory != nullptr, nullptr, "SharedMem is nullptr");
    MEDIA_LOGI("FetchArtPicture size: %{public}d", sharedMemory->GetSize());
    OHOS::Media::SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateImageSource(sharedMemory->GetBase(), sharedMemory->GetSize(),
            sourceOptions, errorCode);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "Failed to create imageSource.");
    OHOS::Media::DecodeOptions decodeOptions;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOptions, errorCode);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Failed to decode imageSource");
    return pixelMap;
}

optional<ohos::multimedia::image::image::PixelMap> AVMetadataExtractorImpl::FetchAlbumCoverSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::fetchArtPicture");
    MEDIA_LOGI("TaiheFetchArtPicture In");

    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "Can't fetchAlbumCover, please set fdSrc or dataSrc.");
        return optional<ohos::multimedia::image::image::PixelMap>(std::nullopt);
    }

    MEDIA_LOGI("TaiheFetchArtPicture task start");
    auto sharedMemory = helper_->FetchArtPicture();
    std::shared_ptr<OHOS::Media::PixelMap> artPicture = ConvertMemToPixelMap(sharedMemory);
    if (artPicture == nullptr) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Failed to fetchAlbumCover");
        return optional<ohos::multimedia::image::image::PixelMap>(std::nullopt);
    }
    return optional<ohos::multimedia::image::image::PixelMap>(std::in_place_t{},
        Image::PixelMapImpl::CreatePixelMap(artPicture));
}

void AVMetadataExtractorImpl::ReleaseSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::release");
    MEDIA_LOGI("TaiheRelease In");
    if (dataSrcCb_ != nullptr) {
        dataSrcCb_->ClearCallbackReference();
        dataSrcCb_ = nullptr;
    }
    if (state_ == OHOS::Media::HelperState::HELPER_STATE_RELEASED) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
    }
    helper_->Release();
}

int32_t AVMetadataExtractorImpl::GetFrameIndexByTimeSync(int64_t timeUs)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::GetFrameIndexByTimeSync");
    timeStamp_ = static_cast<uint64_t>(timeUs);
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
        return -1;
    }

    CHECK_AND_RETURN_RET_LOG(helper_ != nullptr, -1, "inner helper is null.");
    auto res = helper_->GetFrameIndexByTime(timeStamp_, index_);
    if (res != OHOS::Media::MSERR_EXT_API9_OK) {
        MEDIA_LOGE("GetFrameIndexByTimeSync get result SignError");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getFrameIndexByTime failed.");
        return -1;
    }
    return static_cast<int32_t>(index_);
}

int64_t AVMetadataExtractorImpl::GetTimeByFrameIndexSync(int32_t index)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::GetTimeByFrameIndexSync");
    if (index < 0) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_INVALID_PARAMETER, "frame index is not valid");
        return -1;
    }
    index_ = static_cast<uint32_t>(index);
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
        return -1;
    }

    CHECK_AND_RETURN_RET_LOG(helper_ != nullptr, -1, "inner helper is null.");
    auto res = helper_->GetTimeByFrameIndex(index_, timeStamp_);
    if (res != OHOS::Media::MSERR_EXT_API9_OK) {
        MEDIA_LOGE("GetTimeByFrameIndexSync get result SignError");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getTimeByFrameIndex failed.");
        return -1;
    }
    return static_cast<int64_t>(timeStamp_);
}

optional<::ohos::multimedia::image::image::PixelMap> AVMetadataExtractorImpl::FetchFrameByTimeSync(int64_t timeUs,
    AVImageQueryOptions options, PixelMapParams const& param)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorTaihe::TaiheFetchFrameAtTime");
    MEDIA_LOGI("TaiheFetchFrameAtTime in");
    AVMetadataExtractorImpl *taihe = this;
    if (taihe->state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT,
            "Current state is not runnable, can't fetchFrame.");
        return optional<::ohos::multimedia::image::image::PixelMap>(std::nullopt);
    }
    OHOS::Media::PixelMapParams pixelMapParams;
    if (param.height.has_value()) {
        pixelMapParams.dstHeight = param.height.value();
    }
    if (param.width.has_value()) {
        pixelMapParams.dstWidth = param.width.value();
    }
    OHOS::Media::PixelFormat colorFormat = OHOS::Media::PixelFormat::RGBA_8888;
    if (param.colorFormat.has_value()) {
        int32_t formatVal = static_cast<int32_t>(param.colorFormat.value());
        colorFormat = static_cast<OHOS::Media::PixelFormat>(formatVal);
        if (colorFormat != OHOS::Media::PixelFormat::RGB_565 && colorFormat !=
            OHOS::Media::PixelFormat::RGB_888 &&
            colorFormat != OHOS::Media::PixelFormat::RGBA_8888) {
            set_business_error(OHOS::Media::MSERR_INVALID_VAL, "formatVal is invalid");
            return optional<::ohos::multimedia::image::image::PixelMap>(std::nullopt);
        }
    }
    pixelMapParams.colorFormat = colorFormat;
    auto pixelMap = helper_->FetchScaledFrameYuv(timeUs, options.get_value(), pixelMapParams);
    MEDIA_LOGI("TaiheFetchFrameByTime Out");
    return optional<::ohos::multimedia::image::image::PixelMap>(std::in_place_t{},
        Image::PixelMapImpl::CreatePixelMap(pixelMap));
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVMetadataExtractorSync(CreateAVMetadataExtractorSync);