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
#include "media_errors.h"
#include "media_dfx.h"
#include "image_source.h"
#include "media_taihe_utils.h"

using namespace ANI::Media;
using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVMetadataExtractorTaihe"};
}
namespace ANI::Media {

AVMetadataExtractorImpl::AVMetadataExtractorImpl() {}

AVMetadataExtractorImpl::AVMetadataExtractorImpl(AVMetadataExtractorImpl *obj)
{
    if (obj != nullptr) {
        helper_ = obj->helper_;
    }
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
    if (dataSrcCb_ == nullptr) {
        std::shared_ptr<uintptr_t> ptr = std::make_shared<uintptr_t>();
        int64_t errFileSize = -1;
        auto errorCallback = std::reinterpret_pointer_cast<DataSrcCallback>(ptr);
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to check dataSrcCb_");
        return optional<AVDataSrcDescriptor>(std::in_place_t{},
            AVDataSrcDescriptor{std::move(errFileSize), std::move(*errorCallback)});
    }
    int64_t fileSize;
    (void)dataSrcCb_->GetSize(fileSize);
    const std::string callbackName = "readAt";
    std::shared_ptr<uintptr_t> callback;
    int32_t ret = dataSrcCb_->GetCallback(callbackName, callback);
    if (ret != OHOS::Media::MSERR_OK) {
        std::shared_ptr<uintptr_t> ptr = std::make_shared<uintptr_t>();
        int64_t errFileSize = -1;
        auto errorCallback = std::reinterpret_pointer_cast<DataSrcCallback>(ptr);
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "failed to GetCallback");
        return optional<AVDataSrcDescriptor>(std::in_place_t{},
            AVDataSrcDescriptor{std::move(errFileSize), std::move(*errorCallback)});
    }
    auto cacheCallback = std::reinterpret_pointer_cast<DataSrcCallback>(callback);
    AVDataSrcDescriptor fdSrc = AVDataSrcDescriptor{std::move(fileSize), std::move(*cacheCallback)};
    MEDIA_LOGI("TaiheGetDataSrc Out");
    return optional<AVDataSrcDescriptor>(std::in_place_t{}, fdSrc);
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
        auto callbackPtr = std::make_shared<DataSrcCallback>(dataSrc.value().callback);
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

AVMetadata AVMetadataExtractorImpl::FetchMetadataSync()
{
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchMetadata, please set source.");
    }
    AVMetadata res;

    std::shared_ptr<OHOS::Media::Meta> metadata = helper_->GetAVMetadata();
    if (metadata == nullptr) {
        MEDIA_LOGE("ResolveMetadata AVMetadata is nullptr");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "ResolveMetadata fail, metadata is null!");
        return res;
    }
    Location loc;
    map<string, string> customInfo;
    bool ret = true;
    for (const auto &key : OHOS::Media::g_Metadata) {
        if (metadata->Find(key) == metadata->end()) {
            MEDIA_LOGE("failed to find key: %{public}s", key.c_str());
            continue;
        }
        if (key == "latitude") {
            int32_t value;
            ret = metadata->GetData(key, value);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            loc.latitude = value;
            continue;
        } else if (key == "longitude") {
            int32_t value;
            ret = metadata->GetData(key, value);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            loc.longitude = value;
            continue;
        } else if (key == "customInfo") {
            std::shared_ptr<OHOS::Media::Meta> customData = std::make_shared<OHOS::Media::Meta>();
            ret = metadata->GetData(key, customData);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            for (auto iter = customData->begin(); iter != customData->end(); ++iter) {
                OHOS::Media::AnyValueType type = customData->GetValueType(iter->first);
                CHECK_AND_CONTINUE_LOG(type == OHOS::Media::AnyValueType::STRING, "key is not string");
                std::string sValue;
                ret = customData->GetData(iter->first, sValue);
                CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", iter->first.c_str());
                customInfo.emplace(iter->first, sValue);
            }
            continue;
        }
    }
    res.location = optional<Location>(std::in_place_t{}, loc);
    res.customInfo = optional<map<string, string>>(std::in_place_t{}, customInfo);
    return res;
}

AVMetadataExtractor CreateAVMetadataExtractorSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractor::CreateAVMetadataExtractor");
    MEDIA_LOGI("TaiheCreateAVMetadataExtractor In");

    AVMetadataExtractorImpl *extractor = new AVMetadataExtractorImpl();
    std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper =
        OHOS::Media::AVMetadataHelperFactory::CreateAVMetadataHelper();
    extractor->helper_ = avMetadataHelper;
    CHECK_AND_RETURN_RET_LOG(extractor->helper_ != nullptr,
        (make_holder<AVMetadataExtractorImpl, AVMetadataExtractor>(nullptr)), "failed to CreateMetadataHelper");
    MEDIA_LOGI("TaiheCreateAVMetadataExtractor Out");
    return make_holder<AVMetadataExtractorImpl, AVMetadataExtractor>(extractor);
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

int32_t AVMetadataExtractorImpl::GetFrameIndexByTimeSync(double timeUs)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::GetFrameIndexByTimeSync");
    timeStamp_ = static_cast<uint64_t>(timeUs);
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
    }

    auto res = helper_->GetFrameIndexByTime(timeStamp_, index_);
    if (res != OHOS::Media::MSERR_EXT_API9_OK) {
        MEDIA_LOGE("GetFrameIndexByTimeSync get result SignError");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getFrameIndexByTime failed.");
    }
    return static_cast<uint32_t>(index_);
}

double AVMetadataExtractorImpl::GetTimeByFrameIndexSync(int32_t index)
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::GetTimeByFrameIndexSync");
    index_ = static_cast<uint32_t>(index);
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
    }

    auto res = helper_->GetTimeByFrameIndex(index_, timeStamp_);
    if (res != OHOS::Media::MSERR_EXT_API9_OK) {
        MEDIA_LOGE("GetTimeByFrameIndexSync get result SignError");
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getTimeByFrameIndex failed.");
    }
    return static_cast<double>(timeStamp_);
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

uintptr_t AVMetadataExtractorImpl::FetchAlbumCoverSync()
{
    OHOS::Media::MediaTrace trace("AVMetadataExtractorImpl::FetchAlbumCoverSync");
    MEDIA_LOGI("FetchAlbumCoverSync In");
    if (state_ != OHOS::Media::HelperState::HELPER_STATE_RUNNABLE) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
    }

    auto sharedMemory = helper_->FetchArtPicture();
    artPicture_ = ConvertMemToPixelMap(sharedMemory);
    if (artPicture_ == nullptr) {
        set_business_error(OHOS::Media::MSERR_EXT_API9_UNSUPPORT_FORMAT, "Failed to fetchAlbumCover");
    }

    ani_env *env = taihe::get_env();
    ani_object result = {};
    result = MediaTaiheUtils::CreatePixelMap(env, *artPicture_);
    MEDIA_LOGI("FetchAlbumCoverSync Out");

    return reinterpret_cast<uintptr_t>(result);
}
} // namespace ANI::Media

TH_EXPORT_CPP_API_CreateAVMetadataExtractorSync(CreateAVMetadataExtractorSync);
